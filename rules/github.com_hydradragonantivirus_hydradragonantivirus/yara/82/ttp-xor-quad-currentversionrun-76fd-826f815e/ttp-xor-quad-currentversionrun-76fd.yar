rule TTP_XOR_QUAD_CurrentVersionRun_76fd {
  strings:
    $key_76fd = { 25 92 [2] 01 9c [2] 2a b0 [2] 04 92 [2] 10 89 [2] 1f 93 [2] 01 8e [2] 03 8f [2] 18 89 [2] 04 8e [2] 18 a1 }

  condition:
    any of them
}