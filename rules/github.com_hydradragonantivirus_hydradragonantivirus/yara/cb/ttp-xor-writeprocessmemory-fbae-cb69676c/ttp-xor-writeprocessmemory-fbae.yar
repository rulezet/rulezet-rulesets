rule TTP_XOR_WriteProcessMemory_fbae {
  strings:
    $key_fbae = { ac dc [2] 9e fe [2] 98 cb [2] b6 cb [2] 89 d7 }

  condition:
    any of them
}