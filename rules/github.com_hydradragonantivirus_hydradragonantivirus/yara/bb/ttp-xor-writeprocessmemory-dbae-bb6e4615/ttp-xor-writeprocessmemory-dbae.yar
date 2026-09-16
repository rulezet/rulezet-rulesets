rule TTP_XOR_WriteProcessMemory_dbae {
  strings:
    $key_dbae = { 8c dc [2] be fe [2] b8 cb [2] 96 cb [2] a9 d7 }

  condition:
    any of them
}