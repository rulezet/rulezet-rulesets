rule TTP_XOR_QUAD_CurrentVersionRun_9121 {
  strings:
    $key_9121 = { c2 4e [2] e6 40 [2] cd 6c [2] e3 4e [2] f7 55 [2] f8 4f [2] e6 52 [2] e4 53 [2] ff 55 [2] e3 52 [2] ff 7d }

  condition:
    any of them
}