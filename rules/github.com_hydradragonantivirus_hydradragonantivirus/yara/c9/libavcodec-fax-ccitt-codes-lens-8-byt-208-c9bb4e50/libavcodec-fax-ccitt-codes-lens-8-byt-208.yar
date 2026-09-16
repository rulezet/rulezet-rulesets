rule libavcodec_fax_ccitt_codes_lens__8_byt_208_ {
  strings:
    $a0 = { 08 06 04 04 04 04 04 04 05 05 05 05 06 06 06 06 06 06 07 07 07 07 07 07 07 07 07 07 07 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 08 05 05 06 07 08 08 08 08 08 08 09 09 09 09 09 09 09 09 09 09 09 09 09 09 09 06 09 0b 0b 0b 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0a 03 02 02 03 04 04 05 06 06 07 07 07 08 08 09 0a 0a 0a 0b 0b 0b 0b 0b 0b 0b 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c 0a 0c 0c 0c 0c 0c 0c 0d 0d 0d 0d 0d 0d 0d 0d 0d 0d 0d 0d 0d 0d 0d 0d 0d 0d 0d 0d 0b 0b 0b 0c 0c 0c 0c 0c 0c 0c 0c 0c 0c }

  condition:
    $a0
}