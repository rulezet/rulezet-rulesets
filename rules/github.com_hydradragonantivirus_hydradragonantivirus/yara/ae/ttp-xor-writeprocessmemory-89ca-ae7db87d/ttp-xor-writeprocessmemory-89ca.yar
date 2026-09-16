rule TTP_XOR_WriteProcessMemory_89ca {
  strings:
    $key_89ca = { de b8 [2] ec 9a [2] ea af [2] c4 af [2] fb b3 }

  condition:
    any of them
}