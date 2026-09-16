rule TTP_XOR_WriteProcessMemory_891a {
  strings:
    $key_891a = { de 68 [2] ec 4a [2] ea 7f [2] c4 7f [2] fb 63 }

  condition:
    any of them
}