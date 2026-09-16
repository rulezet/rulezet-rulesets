rule TTP_XOR_WriteProcessMemory_893a {
  strings:
    $key_893a = { de 48 [2] ec 6a [2] ea 5f [2] c4 5f [2] fb 43 }

  condition:
    any of them
}