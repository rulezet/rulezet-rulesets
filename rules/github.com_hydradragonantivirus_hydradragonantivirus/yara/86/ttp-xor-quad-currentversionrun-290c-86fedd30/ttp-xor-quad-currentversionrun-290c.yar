rule TTP_XOR_QUAD_CurrentVersionRun_290c {
  strings:
    $key_290c = { 7a 63 [2] 5e 6d [2] 75 41 [2] 5b 63 [2] 4f 78 [2] 40 62 [2] 5e 7f [2] 5c 7e [2] 47 78 [2] 5b 7f [2] 47 50 }

  condition:
    any of them
}