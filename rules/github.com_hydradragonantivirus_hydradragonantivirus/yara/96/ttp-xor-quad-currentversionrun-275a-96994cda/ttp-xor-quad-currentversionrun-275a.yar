rule TTP_XOR_QUAD_CurrentVersionRun_275a {
  strings:
    $key_275a = { 74 35 [2] 50 3b [2] 7b 17 [2] 55 35 [2] 41 2e [2] 4e 34 [2] 50 29 [2] 52 28 [2] 49 2e [2] 55 29 [2] 49 06 }

  condition:
    any of them
}