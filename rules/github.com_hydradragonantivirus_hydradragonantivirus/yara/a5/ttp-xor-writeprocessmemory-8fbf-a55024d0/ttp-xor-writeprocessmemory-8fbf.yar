rule TTP_XOR_WriteProcessMemory_8fbf {
  strings:
    $key_8fbf = { d8 cd [2] ea ef [2] ec da [2] c2 da [2] fd c6 }

  condition:
    any of them
}