rule TTP_XOR_WriteProcessMemory_d38f {
  strings:
    $key_d38f = { 84 fd [2] b6 df [2] b0 ea [2] 9e ea [2] a1 f6 }

  condition:
    any of them
}