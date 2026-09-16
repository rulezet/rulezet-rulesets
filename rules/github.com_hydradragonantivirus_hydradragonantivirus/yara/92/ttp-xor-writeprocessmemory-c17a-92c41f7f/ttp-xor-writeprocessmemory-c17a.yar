rule TTP_XOR_WriteProcessMemory_c17a {
  strings:
    $key_c17a = { 96 08 [2] a4 2a [2] a2 1f [2] 8c 1f [2] b3 03 }

  condition:
    any of them
}