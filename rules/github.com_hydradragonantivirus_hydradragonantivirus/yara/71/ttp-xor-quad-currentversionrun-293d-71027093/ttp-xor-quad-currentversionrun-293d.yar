rule TTP_XOR_QUAD_CurrentVersionRun_293d {
  strings:
    $key_293d = { 7a 52 [2] 5e 5c [2] 75 70 [2] 5b 52 [2] 4f 49 [2] 40 53 [2] 5e 4e [2] 5c 4f [2] 47 49 [2] 5b 4e [2] 47 61 }

  condition:
    any of them
}