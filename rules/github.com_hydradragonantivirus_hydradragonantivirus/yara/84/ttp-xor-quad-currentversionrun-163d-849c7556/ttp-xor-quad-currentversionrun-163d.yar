rule TTP_XOR_QUAD_CurrentVersionRun_163d {
  strings:
    $key_163d = { 45 52 [2] 61 5c [2] 4a 70 [2] 64 52 [2] 70 49 [2] 7f 53 [2] 61 4e [2] 63 4f [2] 78 49 [2] 64 4e [2] 78 61 }

  condition:
    any of them
}