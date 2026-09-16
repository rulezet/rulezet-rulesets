rule TTP_XOR_QUAD_CurrentVersionRun_92ea {
  strings:
    $key_92ea = { c1 85 [2] e5 8b [2] ce a7 [2] e0 85 [2] f4 9e [2] fb 84 [2] e5 99 [2] e7 98 [2] fc 9e [2] e0 99 [2] fc b6 }

  condition:
    any of them
}