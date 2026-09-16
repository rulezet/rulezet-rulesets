rule TTP_XOR_WriteProcessMemory_8945 {
  strings:
    $key_8945 = { de 37 [2] ec 15 [2] ea 20 [2] c4 20 [2] fb 3c }

  condition:
    any of them
}