rule TTP_XOR_QUAD_CurrentVersionRun_9200 {
  strings:
    $key_9200 = { c1 6f [2] e5 61 [2] ce 4d [2] e0 6f [2] f4 74 [2] fb 6e [2] e5 73 [2] e7 72 [2] fc 74 [2] e0 73 [2] fc 5c }

  condition:
    any of them
}