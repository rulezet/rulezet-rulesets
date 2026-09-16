rule TTP_XOR_QUAD_CurrentVersionRun_563d {
  strings:
    $key_563d = { 05 52 [2] 21 5c [2] 0a 70 [2] 24 52 [2] 30 49 [2] 3f 53 [2] 21 4e [2] 23 4f [2] 38 49 [2] 24 4e [2] 38 61 }

  condition:
    any of them
}