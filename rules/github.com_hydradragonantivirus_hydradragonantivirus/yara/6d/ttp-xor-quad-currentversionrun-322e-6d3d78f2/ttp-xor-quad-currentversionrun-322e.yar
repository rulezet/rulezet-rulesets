rule TTP_XOR_QUAD_CurrentVersionRun_322e {
  strings:
    $key_322e = { 61 41 [2] 45 4f [2] 6e 63 [2] 40 41 [2] 54 5a [2] 5b 40 [2] 45 5d [2] 47 5c [2] 5c 5a [2] 40 5d [2] 5c 72 }

  condition:
    any of them
}