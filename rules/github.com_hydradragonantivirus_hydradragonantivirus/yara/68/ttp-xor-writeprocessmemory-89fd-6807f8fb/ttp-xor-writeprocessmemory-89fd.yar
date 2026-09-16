rule TTP_XOR_WriteProcessMemory_89fd {
  strings:
    $key_89fd = { de 8f [2] ec ad [2] ea 98 [2] c4 98 [2] fb 84 }

  condition:
    any of them
}