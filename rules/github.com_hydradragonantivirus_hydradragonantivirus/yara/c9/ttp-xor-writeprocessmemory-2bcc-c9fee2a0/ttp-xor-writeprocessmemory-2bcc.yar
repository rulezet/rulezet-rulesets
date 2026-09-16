rule TTP_XOR_WriteProcessMemory_2bcc {
  strings:
    $key_2bcc = { 7c be [2] 4e 9c [2] 48 a9 [2] 66 a9 [2] 59 b5 }

  condition:
    any of them
}