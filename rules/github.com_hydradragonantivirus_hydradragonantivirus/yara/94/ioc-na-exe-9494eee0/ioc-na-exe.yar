import "hash"
rule IOC_NA_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-14 03:38:16"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "dda58e02acca78a978c8ae8a82b34e3dee6db965b3c101731cbec2850cf5477f" or
    hash.sha256(0, filesize) == "90e4f566d5c15666ff4037b6876350c449e5b0f0f9a87bd0f950012d0d42541b" or
    hash.sha256(0, filesize) == "39c8e9229a2789a66a452eb9ccc656198aef60ab761f4a24794159b91ad67a4b" or
    hash.sha256(0, filesize) == "c99f57b763d90598609eb0b585ca8399057531d171021d3052efdefe26289117" or
    hash.sha256(0, filesize) == "c5c00a192d1427f8d60b64e3e769c7f16b2fee7133dee7c63c042faaea4919fb" or
    hash.sha256(0, filesize) == "4249959b292b1ff31e325395430cd1f438e432fa578d219bdb78983a30019873" or
    hash.sha256(0, filesize) == "3e23c3ee33d73dfaa575173e9467fd32e7bf14c33723b19691a91abefb283ef8" or
    hash.sha256(0, filesize) == "9526a4e0b40f262bc5cd1e07a8b80f465e052c18b3698e496ba0e2dd6549127a" or
    hash.sha256(0, filesize) == "827f8d64cd3023b078e30dcc014306c90fb3383b75b58b9479d0d19dcfc15894" or
    hash.sha256(0, filesize) == "f4bdddb45e727c8699340ba8d520a37e07b0becb4c571a67b3c9f4ce3a138213" or
    hash.sha256(0, filesize) == "8094ecda8ca0f8d5adb805dfef15a5d13c1dd670c3fd701ea98c36d19fde8cfd" or
    hash.sha256(0, filesize) == "08cb1432c512df0370577dc50549ad06f729858143017fe00f79fcb218872d01" or
    hash.sha256(0, filesize) == "b760fd1b8d86af6b67ac24e6a269f2ffbc818d37f7930fb562cce1331213d031" or
    hash.sha256(0, filesize) == "14b8daae29a4a354bdb62a5c3034941a1be3a161193489a624c8de3450a9442d" or
    hash.sha256(0, filesize) == "02d956d1f2c9ecdc43ebcbfef06dc160cdd9e5e31f50c692bde9ed1dd9797040" or
    hash.sha256(0, filesize) == "e5f25600b1e6483536bae239c5ff59e496fad54cd9ca1d82be94e26f27be5fa8" or
    hash.sha256(0, filesize) == "0985988c4ec01ce89ab73cd68d1e4d3944c8eafc4b5a69d0cd451487e97ff6a8" or
    hash.sha256(0, filesize) == "5772ac53f3ea00ee06f592ea27fe7f119f2027de5dcf72005a35a4302eb2d524" or
    hash.sha256(0, filesize) == "41b8a012d8dd2aa525aa05e5d296e13d4994110cefa41068adfb80eec0e3efe7" or
    hash.sha256(0, filesize) == "c3f6354c94ae880d0254f356f2836aaf4aec81b903e4054f75f6e517183e9fce" or
    hash.sha256(0, filesize) == "2aaa4c723b5868576aa1be98426763d3c75b1255aa639516c46d5867d2e970a4" or
    hash.sha256(0, filesize) == "36464f131691f5a812e22d4255377f79a475700185352606586f671b9ab63b66" or
    hash.sha256(0, filesize) == "d6e31c14d40784a2ff3b92ddea17ceb6eace0d64c4526bf17f8932700528dfe1" or
    hash.sha256(0, filesize) == "871c57f351c6debafe3210ce09ccdb78f8ec84223ac7d70ab96126b1bf5f6d6c" or
    hash.sha256(0, filesize) == "ca45f40c10f30d2c60b2ab67afffc295763d61c890f92b4bc71885d96ac56e18" or
    hash.sha256(0, filesize) == "8a119d3b9fce9c74bec4f0a150d29ff043af16ec7202b42c23b4c77da5266676" or
    hash.sha256(0, filesize) == "02ee3096c2471e5645404518b3fefd9c72b473bcefbd7c2ee167256546cdd030" or
    hash.sha256(0, filesize) == "d102730f766be0466151499f76d91af1c8f4c57ed3d973fcf60f1ff16a0b2594" or
    hash.sha256(0, filesize) == "12e7cbc39bce880ee356a8946fe22b8dfe01a8a21b90c0291ec774d5bc640f44" or
    hash.sha256(0, filesize) == "e3ca09965edf62f810d4889f9650b4669791102332ed761769f0ca9dabed1908" or
    hash.sha256(0, filesize) == "c9fcea3aed96b45b349ee794e0cd17c073b76a251f5dbc2285a2025e76225654" or
    hash.sha256(0, filesize) == "d09f9f6cdc590384d14c7aa5e5580fc0a358d0aa0f05199d12faf6ee17937646" or
    hash.sha256(0, filesize) == "ee36161c6b3635240df4c30f370420483174cc1a4999a386952d452d0de03c40" or
    hash.sha256(0, filesize) == "e61ed0d2ac83d2875180b1a33e04834aa6ca7dba7a5663e8d6e65a4482537576" or
    hash.sha256(0, filesize) == "03c4bbba0969018b4e4e048b8f3c52ce0d99a3e37da9ed11a18997e8a836f28f" or
    hash.sha256(0, filesize) == "c28c4cec1d98e3f612108826f92aef8d25da93ec22ac1b91523e944126ad0dbb" or
    hash.sha256(0, filesize) == "78a194ef979ef86b3001e42bde28be13a7efa2f5744ac4b5126036bbce309606" or
    hash.sha256(0, filesize) == "ecbff5a6e21170f5156f18ae42e78f6b2c38c36889fee23121683151b5e6e698" or
    hash.sha256(0, filesize) == "a56f0f054bd35ec2153c00022e9c811c24e2a352e7e1a0e7c23daa96d86da910" or
    hash.sha256(0, filesize) == "2d779ca15bff11fdaeaaead808f4887d4bbd30b441ce9d4ef6dfb28b748e8769" or
    hash.sha256(0, filesize) == "1c5682f07fcc6d16f137dc06f714388e040eb5a3209152bfff09563b545ff4ee" or
    hash.sha256(0, filesize) == "ff625dd0483caccac07b4233e3f8174a2237b8382da090067dc66213f5d9c8f5" or
    hash.sha256(0, filesize) == "588f49a1ba2f244d08911daaf351bc36ac8bffa5802eefe73a0ef1b7c4fc2a7e" or
    hash.sha256(0, filesize) == "047c2fb47c8227863ce3f9e4fe5c1e8fee7e3172019d56a27734178bb20a718c" or
    hash.sha256(0, filesize) == "686d46dc014ea066ed05b568eacffa901ab77f09ea65773ecd7ce8daed8b6b14" or
    hash.sha256(0, filesize) == "694b86530d202beb35223e351fe7cf8d5221b8b61b9326571039451a76272564" or
    hash.sha256(0, filesize) == "f4c4986fd011f3ef1223329e0433fd0d8766d27596bb02566b7afdcba0f21ea7" or
    hash.sha256(0, filesize) == "fe87527ba3585e4e2437669ad1d4922dca958a78ed2416ed8426a8abf0ee2f6b" or
    hash.sha256(0, filesize) == "7639d10533c0fbbe7a72fbc584a77b48b2758d6b8e4587a6f2e78bb7dd715a2d" or
    hash.sha256(0, filesize) == "9a4b6b2f92768653a963bc7658be529a27e94bf082d8c8843f189ecb85dcc653" or
    hash.sha256(0, filesize) == "f33cdca93db97c4b84af9f01216f3b7bcb3cf1865df84cb3b64fbbeed7057a2a" or
    hash.sha256(0, filesize) == "4be5f0cbc0f19546855afc9e8af0eafea9f10fb751ec9c1dea7ab88fb4543c21" or
    hash.sha256(0, filesize) == "764e1d6e17b2bf3ff9beab19e067594d2a7f1fdcd9f3fe74031c11f650aa2f49" or
    hash.sha256(0, filesize) == "470cf66bec58f48d4290d8440bef7c00fcfbd0f334504c5d2ac6739b8929ea7b" or
    hash.sha256(0, filesize) == "3bad32b4a4a4a24f88120c59519a942f29c71bbc638fda3c0b06655c29742c43" or
    hash.sha256(0, filesize) == "5bba406a5a9d3739ec90e3d6d5e619c849807e6e8d50d80ff80f7a34bb4b30a8" or
    hash.sha256(0, filesize) == "296a2dbc2d3de1c05763952fb82b7cdd2d5f6deccad03c9617da144761993413" or
    hash.sha256(0, filesize) == "4dafdfbf52d678a0138311e426f4b5681b0adfcbf63eacf941040be1a1b62508" or
    hash.sha256(0, filesize) == "94e606d5814003e1ad02da673542321ff27f3c0900e5d80c10f5a2b163e9be95" or
    hash.sha256(0, filesize) == "0808202fc3bd5e570b2106a4f991de5beeee739960b1167a590da92727b813a6" or
    hash.sha256(0, filesize) == "6c485e5e8e555eea6d9df398da467fc006baa7b621dcc8d87730b32b037e5525" or
    hash.sha256(0, filesize) == "a31e66233b55244dea9219f5b5a4df56732ea52b4d2c7dac246851fcb9b9c318" or
    hash.sha256(0, filesize) == "97cd6e5130cbaa45bd0281318c61c122cca866764dcfc87670422dbe4bfa8d6b" or
    hash.sha256(0, filesize) == "7aa30ac897fcf18158968453dcaa7a57d39aea3f5292a949bfede803e55bc8f1" or
    hash.sha256(0, filesize) == "a0b708c25e2fce2346235d0bb42abc98432e664bec6e925a04e9636277ead082" or
    hash.sha256(0, filesize) == "d790818dae55b8474612f9a1d45d4cffd35d083dc4ee2215b94ad9acb1aad808" or
    hash.sha256(0, filesize) == "2e3b753447ccd7d4a766dce1392d884fc6a3632d858f77ad19465a6504708ae6" or
    hash.sha256(0, filesize) == "24c0f541525bb734bd6ee6ce4328b752fba618092cbad8131e7418341da99134" or
    hash.sha256(0, filesize) == "e51d0b81ca8d23771538b6f9f787293c86fb78ad2d30fb09a57a9f8bc301dac7" or
    hash.sha256(0, filesize) == "6006d9cff2c3f472eeb4ca93ecf66a5e77014079508b6b0e75e1d58a0335ff62" or
    hash.sha256(0, filesize) == "29c63521ac9ec647a95c3330a23aced7ce53f1101c23a71f2d30350bfcaa7b27" or
    hash.sha256(0, filesize) == "444ed0d8b62bdd8da294c6a49e47a7f8a15fcec43409780ea00997a0bf53ffe5" or
    hash.sha256(0, filesize) == "6f40d5c35c41245183c6866fb0a4f8a60c5a70079213b1c76792c269f174364f" or
    hash.sha256(0, filesize) == "c957b6e7aeb2e6b6af16e5da1a09ccd6d5eb139a0db5429cfcc67a0a954c9bbf" or
    hash.sha256(0, filesize) == "46a95f00106f48d7ecf75c41fac059e5f5766f7cefec73e2638d9dfbe27e7f10" or
    hash.sha256(0, filesize) == "7c31d4fe105e60a9729dbd33357ddc20f3526a5ec2dfd1fc69eaa1668f289804" or
    hash.sha256(0, filesize) == "6927a9e73bf55a3401c967648cfc9f0d1d6cbf7cf452dd483620992d7d8b34e2" or
    hash.sha256(0, filesize) == "7e512bb8c1dade78162ab6116b93dd3db2cbf91dddf09d05955fa5fdcdbd7113" or
    hash.sha256(0, filesize) == "557e98b9d9d27da718e9ea7e20535535f3b0f796fe85a636eb14c418cc28c21a" or
    hash.sha256(0, filesize) == "bb4d377bc3a7dd434ee93d3de114df09e1985dfcca00d344d9ad656dbbc07493" or
    hash.sha256(0, filesize) == "dd69c8ab0e6f97b1e877054189d93360498d5bde5a61ec6aa100e04741c303f9" or
    hash.sha256(0, filesize) == "cf03c50f7197f7511f36824745a247f4dcedb427689fcb1f34074f07ed99b5ce" or
    hash.sha256(0, filesize) == "28dc1b057af09d247f9bdede84202dd18aa81b30a6583a152a101d1b2d91f26b" or
    hash.sha256(0, filesize) == "a4a651ae85e06287fdbd48c3d753856b07429f1c8b9566312cab224980f7895c" or
    hash.sha256(0, filesize) == "93f4f7dd1458ebc9caa287fe4a81737a417a75ab8e3a4a150c5c907f87b51d11" or
    hash.sha256(0, filesize) == "235f5430842be63a9bca58fb148480b6d6a1f0a0631ace17e78bf8430c5f98e0" or
    hash.sha256(0, filesize) == "d61440747490d4b403f4436639207f3a665dca0cd035267ae044ceff6a0c80e9" or
    hash.sha256(0, filesize) == "1809dddc2ed1656288e8932cf69022e58b688310423dcb7159fc73b38ee5abb0" or
    hash.sha256(0, filesize) == "b3b3761301129116546060fdda707826c64c631f45c7af948a809fc4e81cd87c" or
    hash.sha256(0, filesize) == "ff8973e265cde0ecfc91cb81ae4af75946b2cfcaa772b5cd1390c176e788175f" or
    hash.sha256(0, filesize) == "dcf2b30da73634394e398e44c84ea1f525a6e2b5f29114a0c504c50e119515b5" or
    hash.sha256(0, filesize) == "e40ee5b484b1f3e630bb257ab3424acefd5b2bc9979664415774a080e69623ad" or
    hash.sha256(0, filesize) == "f51088a42ffcbd2b95644e0861da35421244abe85928ada80ad383345ff0167f" or
    hash.sha256(0, filesize) == "84ff81ced73bc59be766c505ef9e65c6f898f334d3de0510d18248254119b326" or
    hash.sha256(0, filesize) == "c3efd2ad3d87e34d909c43790872b69e41232c05d8d498d1e1ee6c928573a33e" or
    hash.sha256(0, filesize) == "86951a2c31972c2d34d5eb44f518c05a449c00d751163282639f41bc5fac09f3" or
    hash.sha256(0, filesize) == "75386126b0ae0fb4e2f71f083c56ac8fa726482058e2b44274c6bbd51cd88b59" or
    hash.sha256(0, filesize) == "9b1d3802c41f21dcfc6ae41d795a56f200bd4298424b5fd9f4f66a4e5de88d65" or
    hash.sha256(0, filesize) == "f890008561d6268df4e91f4d14c9ec70e42bbb8f7af20fb68e368e542edebc16" or
    hash.sha256(0, filesize) == "1ded59a79c592a70a138f44b71118e2a7f86663902557cf6b8a109989ea53c7d" or
    hash.sha256(0, filesize) == "604c88cf909edfb72deda4ba7e0a78a7981fb9420df6e367c174d098e7460f3b" or
    hash.sha256(0, filesize) == "8022240f5a37f269d0a553c7dff56748864cadeafd8a603ff2920cc69c6bbf76" or
    hash.sha256(0, filesize) == "67b6d2863ac03575f1643fd37379908ece6763943a26163d8f72d345bf1dbcbf" or
    hash.sha256(0, filesize) == "f6a51523b06781d76acee7cc96c996852e35ef0e053e5c4ec5604084cbbdaf3a" or
    hash.sha256(0, filesize) == "ffede509da3e56af0d1a53dbac78a5d9fa35ce43b35f4df847f88f9b583ea709" or
    hash.sha256(0, filesize) == "d363c2dc7eadf1fbfc9bee1983f948677d4495ec13682c6298cfc8647fa47b54" or
    hash.sha256(0, filesize) == "76ea6fc5e2e808633b789fd8c300e15bca434185c6007de3eb98ed1e6dc70070" or
    hash.sha256(0, filesize) == "044058594de29392ad9bb466f082e9f276a19c7ebe6718f15be2075fd4351d69" or
    hash.sha256(0, filesize) == "0f49b20d665b676b9747fb999382df30f011d8d70284898338b27b80cba3ff1e" or
    hash.sha256(0, filesize) == "2f9666700b7a72f77462a3bf62380c47989a0a47e80c544a91b46c3b39d023c0" or
    hash.sha256(0, filesize) == "2018c59cb48d035db9403e9a6c647c8054369fdaff3fc8bf2284607a6a792e97" or
    hash.sha256(0, filesize) == "a6f065630c7b482267b7fd73a39c55615b8e6e35e258c1798ca42878ea989905" or
    hash.sha256(0, filesize) == "3f5c81d5d3aedabfaf11533ea280b538a65b2f5dd9ee6129f38f1684399366f3" or
    hash.sha256(0, filesize) == "7f25012f931ae9d691b9b2e393ec959eec7bad5987805440f325b13b3c033957" or
    hash.sha256(0, filesize) == "6521d0033c9c95469564c86efaefe94eb653f46a1ccb7750968d7c54e0fd90ca" or
    hash.sha256(0, filesize) == "efc9826c30aba11a06834d0e31c10f7ddb804fda6c05a02b796f4084d3e2ffab" or
    hash.sha256(0, filesize) == "9672eb651f72a3dc2a2b676d56d5e3424392123e3ae883719097af836129eb34" or
    hash.sha256(0, filesize) == "eec69f942751816a1f48afa25f329d5ea8e630fda1604be8e1a688046d63338a" or
    hash.sha256(0, filesize) == "9084ecef307c10374f2b4f6d54f7ab929a33ae254b349abf3f7399a8e6cb381f" or
    hash.sha256(0, filesize) == "eedbc0caf5c43d780e840abda5c3dc64721dfd24c0da7143440418317ba1502f" or
    hash.sha256(0, filesize) == "df5397b08e1b72fbf42290033aa11934e895488c93b76e608542fbb49d2e0f98" or
    hash.sha256(0, filesize) == "8538681af5bcf6c5742e9407c89c6caabe24b0453397b1712448177bff21f6d1" or
    hash.sha256(0, filesize) == "320f28727f308f0af628c0c1caf800bcb1754bd14df74361d5cefbaa5e148a8f" or
    hash.sha256(0, filesize) == "38d18a3ec97b64fa831a7521126687baa6cdbf0a859a92c500549fd25df7ebbc" or
    hash.sha256(0, filesize) == "c9a332638e2409f1b8366c9f4ede9b939540c367eab9eba3aa2f935ad74c2a9c" or
    hash.sha256(0, filesize) == "aa0668633c7c710b0a09adc99362b4a3547307f0b3f1338ae731c35d9b071d88" or
    hash.sha256(0, filesize) == "59bc63fd20252adcfdb6ccd58c036c0938354e467d47bec626c1063791f1151f" or
    hash.sha256(0, filesize) == "7f17d3d47f053498a3efecab532932dcc8018e3ee0da60fb090be0abc3fa5a82" or
    hash.sha256(0, filesize) == "b5acf14cdac40be590318dee95425d0746e85b1b7b1cbd14da66f21f2522bf4d" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}