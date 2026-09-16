rule TTP_XOR_QUAD_CurrentVersionRun_30fd {
  strings:
    $key_30fd = { 63 92 [2] 47 9c [2] 6c b0 [2] 42 92 [2] 56 89 [2] 59 93 [2] 47 8e [2] 45 8f [2] 5e 89 [2] 42 8e [2] 5e a1 }

  condition:
    any of them
}