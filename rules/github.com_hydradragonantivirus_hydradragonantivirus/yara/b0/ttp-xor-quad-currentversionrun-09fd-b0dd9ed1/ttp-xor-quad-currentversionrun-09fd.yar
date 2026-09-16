rule TTP_XOR_QUAD_CurrentVersionRun_09fd {
  strings:
    $key_09fd = { 5a 92 [2] 7e 9c [2] 55 b0 [2] 7b 92 [2] 6f 89 [2] 60 93 [2] 7e 8e [2] 7c 8f [2] 67 89 [2] 7b 8e [2] 67 a1 }

  condition:
    any of them
}