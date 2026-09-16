rule PEiD_01482_PcShare____________v4_0_____________ {
  meta:
    description = "[Convert Base64 to ASCII UGNTaGFyZSDDjsOEwrzDvsOAwqbCsMOzw4bDtyB2NC4wIC0+IMOOw57Cv8OJwrfDh8OSw6k=]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 90 34 40 00 68 B6 28 40 00 64 A1 }

  condition:
    $a
}