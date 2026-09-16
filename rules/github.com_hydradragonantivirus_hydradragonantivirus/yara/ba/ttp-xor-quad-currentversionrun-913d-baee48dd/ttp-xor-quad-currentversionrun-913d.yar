rule TTP_XOR_QUAD_CurrentVersionRun_913d {
  strings:
    $key_913d = { c2 52 [2] e6 5c [2] cd 70 [2] e3 52 [2] f7 49 [2] f8 53 [2] e6 4e [2] e4 4f [2] ff 49 [2] e3 4e [2] ff 61 }

  condition:
    any of them
}