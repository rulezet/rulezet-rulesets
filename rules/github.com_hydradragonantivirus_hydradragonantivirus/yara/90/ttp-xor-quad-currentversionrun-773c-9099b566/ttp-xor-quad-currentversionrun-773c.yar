rule TTP_XOR_QUAD_CurrentVersionRun_773c {
  strings:
    $key_773c = { 24 53 [2] 00 5d [2] 2b 71 [2] 05 53 [2] 11 48 [2] 1e 52 [2] 00 4f [2] 02 4e [2] 19 48 [2] 05 4f [2] 19 60 }

  condition:
    any of them
}