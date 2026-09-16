rule TTP_XOR_WriteProcessMemory_dced {
  strings:
    $key_dced = { 8b 9f [2] b9 bd [2] bf 88 [2] 91 88 [2] ae 94 }

  condition:
    any of them
}