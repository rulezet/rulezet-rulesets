rule TTP_XOR_QUAD_CurrentVersionRun_9880 {
  strings:
    $key_9880 = { cb ef [2] ef e1 [2] c4 cd [2] ea ef [2] fe f4 [2] f1 ee [2] ef f3 [2] ed f2 [2] f6 f4 [2] ea f3 [2] f6 dc }

  condition:
    any of them
}