rule TTP_XOR_QUAD_CurrentVersionRun_20fd {
  strings:
    $key_20fd = { 73 92 [2] 57 9c [2] 7c b0 [2] 52 92 [2] 46 89 [2] 49 93 [2] 57 8e [2] 55 8f [2] 4e 89 [2] 52 8e [2] 4e a1 }

  condition:
    any of them
}