rule TTP_XOR_WriteProcessMemory_898f {
  strings:
    $key_898f = { de fd [2] ec df [2] ea ea [2] c4 ea [2] fb f6 }

  condition:
    any of them
}