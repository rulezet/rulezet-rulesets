rule TTP_XOR_WriteProcessMemory_e387 {
  strings:
    $key_e387 = { b4 f5 [2] 86 d7 [2] 80 e2 [2] ae e2 [2] 91 fe }

  condition:
    any of them
}