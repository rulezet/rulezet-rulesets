rule TTP_XOR_WriteProcessMemory_caae {
  strings:
    $key_caae = { 9d dc [2] af fe [2] a9 cb [2] 87 cb [2] b8 d7 }

  condition:
    any of them
}