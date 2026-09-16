rule TTP_XOR_QUAD_CurrentVersionRun_323e {
  strings:
    $key_323e = { 61 51 [2] 45 5f [2] 6e 73 [2] 40 51 [2] 54 4a [2] 5b 50 [2] 45 4d [2] 47 4c [2] 5c 4a [2] 40 4d [2] 5c 62 }

  condition:
    any of them
}