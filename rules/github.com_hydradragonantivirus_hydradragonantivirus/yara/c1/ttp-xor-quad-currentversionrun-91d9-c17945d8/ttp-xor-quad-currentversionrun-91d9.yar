rule TTP_XOR_QUAD_CurrentVersionRun_91d9 {
  strings:
    $key_91d9 = { c2 b6 [2] e6 b8 [2] cd 94 [2] e3 b6 [2] f7 ad [2] f8 b7 [2] e6 aa [2] e4 ab [2] ff ad [2] e3 aa [2] ff 85 }

  condition:
    any of them
}