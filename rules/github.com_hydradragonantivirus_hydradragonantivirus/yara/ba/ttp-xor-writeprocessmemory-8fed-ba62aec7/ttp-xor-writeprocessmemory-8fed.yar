rule TTP_XOR_WriteProcessMemory_8fed {
  strings:
    $key_8fed = { d8 9f [2] ea bd [2] ec 88 [2] c2 88 [2] fd 94 }

  condition:
    any of them
}