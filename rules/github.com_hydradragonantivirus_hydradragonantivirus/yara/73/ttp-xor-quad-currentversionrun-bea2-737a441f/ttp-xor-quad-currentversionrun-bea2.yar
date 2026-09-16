rule TTP_XOR_QUAD_CurrentVersionRun_bea2 {
  strings:
    $key_bea2 = { ed cd [2] c9 c3 [2] e2 ef [2] cc cd [2] d8 d6 [2] d7 cc [2] c9 d1 [2] cb d0 [2] d0 d6 [2] cc d1 [2] d0 fe }

  condition:
    any of them
}