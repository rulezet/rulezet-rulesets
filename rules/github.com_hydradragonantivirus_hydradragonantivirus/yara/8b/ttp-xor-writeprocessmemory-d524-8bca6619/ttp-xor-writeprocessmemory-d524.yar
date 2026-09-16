rule TTP_XOR_WriteProcessMemory_d524 {
  strings:
    $key_d524 = { 82 56 [2] b0 74 [2] b6 41 [2] 98 41 [2] a7 5d }

  condition:
    any of them
}