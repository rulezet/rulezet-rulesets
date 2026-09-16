rule TTP_XOR_QUAD_CurrentVersionRun_9230 {
  strings:
    $key_9230 = { c1 5f [2] e5 51 [2] ce 7d [2] e0 5f [2] f4 44 [2] fb 5e [2] e5 43 [2] e7 42 [2] fc 44 [2] e0 43 [2] fc 6c }

  condition:
    any of them
}