rule TTP_XOR_WriteProcessMemory_8f8f {
  strings:
    $key_8f8f = { d8 fd [2] ea df [2] ec ea [2] c2 ea [2] fd f6 }

  condition:
    any of them
}