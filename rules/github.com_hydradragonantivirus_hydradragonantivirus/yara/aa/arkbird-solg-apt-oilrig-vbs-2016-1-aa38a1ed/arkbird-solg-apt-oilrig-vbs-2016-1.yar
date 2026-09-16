rule ARKBIRD_SOLG_APT_Oilrig_VBS_2016_1: FILE {
  meta:
    description = "Detect VBS script in base 64 used by OilRig (2016)"
    author      = "Arkbird_SOLG"
    id          = "5cc3a3f1-4f2f-56c4-af69-8652d22b6730"
    date        = "2020-08-26"
    modified    = "2021-07-13"
    reference   = "https://twitter.com/Arkbird_SOLG/status/1298758788028264450"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-26/APT_OilRig_2016.yar#L4-L23"
    license_url = "N/A"
    logic_hash  = "a6c42c46c80ca79b01aa0475c823aeccef416a0f8c2f58db95392cbe125b2fad"
    score       = 75
    quality     = 63
    tags        = "FILE"
    hash1       = "1edbb818ea75919bb70bd2496e789e89d26c94cdf65ab61ebb5f1403d45d323c"
    hash2       = "1191d5c1dd7f6ac38b8d72bee37415b3ff1c28a8f907971443ac3a36906e8bf5"

  strings:
    $block1 = "SE9NRT0iJXB1YmxpYyVcTGlicmFyaWVzXCI"
    $block2 = "ClNFUlZFUj0iaHR0"
    $block3 = "V4LmFzcHg/cmVx"
    $block4 = "j0icG93ZXJzaGVsbCAiIiZ7JHdjPShuZXctb2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50KTskd2MuVXNlRGVmYXVsdENyZWRlbnRpYWxzPSR0cnVlOyR3Yy5IZWFkZXJzLmFkZCgnQWNjZXB0JywnKi8qJyk7JHdjLkhlYWRlcnMuYWRkKCdVc2VyLUFnZW50JywnTWljcm9zb2Z0IEJJVFMvNy43Jyk7d2hpbGUoMSl7dHJ5eyRyPUdldC1SYW5kb207JHdjLkRvd25sb2FkRmls"
    $block5 = { 69 49 4e 43 6b 4e 79 5a 57 46 30 5a 55 39 69 61 6d 56 6a 64 43 67 69 56 31 4e 6a 63 6d 6c 77 64 43 35 54 61 47 56 73 62 43 49 70 4c 6c 4a 31 62 69 42 53 5a 58 42 73 59 57 [1-4] 45 52 33 62 69 77 69 4c 56 38 [1-4] 4a 6b 64 32 34 69 4b 53 }
    $block6 = "0iIiINCkNyZWF0ZU9iamVjdCgiV1NjcmlwdC5TaGVsbCIpLlJ1biBSZXBsYWNlKERvd25sb2FkRXhlY3V0ZSwiLV8iLCJiYXQ"
    $block7 = "Qprb21jPSJwb3dlcnNoZWxsIC1leGVjIEJ5cGFzcyAtRmlsZSAiJk"
    $block8 = { 0a b7 9a b5 e3 9b 8d e7 2d 59 27 2b 8a 9b 52 85 e9 65 46 e9 [1-4] d4 }

  condition:
    filesize < 2KB and 6 of them
}