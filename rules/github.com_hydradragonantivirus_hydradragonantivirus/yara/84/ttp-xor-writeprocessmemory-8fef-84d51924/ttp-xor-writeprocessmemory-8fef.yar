rule TTP_XOR_WriteProcessMemory_8fef {
  strings:
    $key_8fef = { d8 9d [2] ea bf [2] ec 8a [2] c2 8a [2] fd 96 }

  condition:
    any of them
}