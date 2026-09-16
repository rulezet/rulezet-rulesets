rule id_software_game_video: ROQ {
  meta:
    author = "Joan Bono"

  strings:
    $a = { 84 10 FF FF FF FF 1E 00 }

  condition:
    $a at 0
}