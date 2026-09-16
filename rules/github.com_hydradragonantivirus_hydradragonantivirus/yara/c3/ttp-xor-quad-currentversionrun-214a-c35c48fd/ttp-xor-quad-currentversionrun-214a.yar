rule TTP_XOR_QUAD_CurrentVersionRun_214a {
  strings:
    $key_214a = { 72 25 [2] 56 2b [2] 7d 07 [2] 53 25 [2] 47 3e [2] 48 24 [2] 56 39 [2] 54 38 [2] 4f 3e [2] 53 39 [2] 4f 16 }

  condition:
    any of them
}