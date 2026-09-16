rule TTP_XOR_QUAD_CurrentVersionRun_323d {
  strings:
    $key_323d = { 61 52 [2] 45 5c [2] 6e 70 [2] 40 52 [2] 54 49 [2] 5b 53 [2] 45 4e [2] 47 4f [2] 5c 49 [2] 40 4e [2] 5c 61 }

  condition:
    any of them
}