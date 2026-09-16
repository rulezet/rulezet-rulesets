rule picasa_material_exchange_music: MXF {
  meta:
    author = "Joan Bono"

  strings:
    $a = "<CTransTimeline>"

  condition:
    $a at 0
}