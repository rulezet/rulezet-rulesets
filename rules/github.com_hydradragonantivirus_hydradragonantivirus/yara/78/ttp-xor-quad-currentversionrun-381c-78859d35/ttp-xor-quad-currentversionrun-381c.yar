rule TTP_XOR_QUAD_CurrentVersionRun_381c {
  strings:
    $key_381c = { 6b 73 [2] 4f 7d [2] 64 51 [2] 4a 73 [2] 5e 68 [2] 51 72 [2] 4f 6f [2] 4d 6e [2] 56 68 [2] 4a 6f [2] 56 40 }

  condition:
    any of them
}