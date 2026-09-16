rule TTP_XOR_QUAD_CurrentVersionRun_327e {
  strings:
    $key_327e = { 61 11 [2] 45 1f [2] 6e 33 [2] 40 11 [2] 54 0a [2] 5b 10 [2] 45 0d [2] 47 0c [2] 5c 0a [2] 40 0d [2] 5c 22 }

  condition:
    any of them
}