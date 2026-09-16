rule TTP_XOR_QUAD_CurrentVersionRun_98cb {
  strings:
    $key_98cb = { cb a4 [2] ef aa [2] c4 86 [2] ea a4 [2] fe bf [2] f1 a5 [2] ef b8 [2] ed b9 [2] f6 bf [2] ea b8 [2] f6 97 }

  condition:
    any of them
}