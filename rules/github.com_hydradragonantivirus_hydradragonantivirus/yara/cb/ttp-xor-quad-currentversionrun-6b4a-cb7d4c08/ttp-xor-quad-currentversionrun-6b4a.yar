rule TTP_XOR_QUAD_CurrentVersionRun_6b4a {
  strings:
    $key_6b4a = { 38 25 [2] 1c 2b [2] 37 07 [2] 19 25 [2] 0d 3e [2] 02 24 [2] 1c 39 [2] 1e 38 [2] 05 3e [2] 19 39 [2] 05 16 }

  condition:
    any of them
}