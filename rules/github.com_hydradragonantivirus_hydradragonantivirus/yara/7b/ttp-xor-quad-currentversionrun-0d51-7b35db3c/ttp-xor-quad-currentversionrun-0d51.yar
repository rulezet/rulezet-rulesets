rule TTP_XOR_QUAD_CurrentVersionRun_0d51 {
  strings:
    $key_0d51 = { 5e 3e [2] 7a 30 [2] 51 1c [2] 7f 3e [2] 6b 25 [2] 64 3f [2] 7a 22 [2] 78 23 [2] 63 25 [2] 7f 22 [2] 63 0d }

  condition:
    any of them
}