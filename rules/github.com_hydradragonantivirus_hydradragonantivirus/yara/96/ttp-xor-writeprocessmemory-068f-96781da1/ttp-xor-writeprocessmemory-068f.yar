rule TTP_XOR_WriteProcessMemory_068f {
  strings:
    $key_068f = { 51 fd [2] 63 df [2] 65 ea [2] 4b ea [2] 74 f6 }

  condition:
    any of them
}