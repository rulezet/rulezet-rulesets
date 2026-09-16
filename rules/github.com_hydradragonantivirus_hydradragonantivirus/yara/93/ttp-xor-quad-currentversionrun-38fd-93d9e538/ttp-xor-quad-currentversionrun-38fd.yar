rule TTP_XOR_QUAD_CurrentVersionRun_38fd {
  strings:
    $key_38fd = { 6b 92 [2] 4f 9c [2] 64 b0 [2] 4a 92 [2] 5e 89 [2] 51 93 [2] 4f 8e [2] 4d 8f [2] 56 89 [2] 4a 8e [2] 56 a1 }

  condition:
    any of them
}